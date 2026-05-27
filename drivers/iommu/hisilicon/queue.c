// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 * Description: UMMU Queue Resource Management. Somewhat based on arm-smmu-v3.c
 * Copyright (C) 2025 ARM Limited
 */

#define pr_fmt(fmt) "UMMU: " fmt

#include <linux/iopoll.h>
#include <linux/dma-mapping.h>
#include <linux/log2.h>

#include "ummu.h"
#include "regs.h"
#include "sva.h"
#include "queue.h"

#define ENTRY_DWORDS_TO_SIZE(dwords) ((dwords) << 3)

struct ummu_queue_poll {
	ktime_t timeout;
	u32 delay;
	u32 spin_cnt;
	bool wfe;
};

/* Low-level queue manipulation functions */
static bool ummu_queue_has_space(struct ummu_ll_queue *q, u32 n)
{
	u32 space, prod, cons;

	prod = Q_IDX(q, q->prod);
	cons = Q_IDX(q, q->cons);
	if (Q_WRP(q, q->prod) == Q_WRP(q, q->cons))
		space = (1UL << q->log2size) - (prod - cons);
	else
		space = cons - prod;

	return space >= n;
}

static bool ummu_queue_full(struct ummu_ll_queue *q)
{
	return Q_IDX(q, q->prod) == Q_IDX(q, q->cons) &&
	       Q_WRP(q, q->prod) != Q_WRP(q, q->cons);
}

bool ummu_queue_empty(struct ummu_ll_queue *q)
{
	return Q_IDX(q, q->prod) == Q_IDX(q, q->cons) &&
	       Q_WRP(q, q->prod) == Q_WRP(q, q->cons);
}

static bool ummu_queue_consumed(struct ummu_ll_queue *q, u32 prod)
{
	return ((Q_WRP(q, q->cons) == Q_WRP(q, prod)) &&
		(Q_IDX(q, q->cons) > Q_IDX(q, prod))) ||
	       ((Q_WRP(q, q->cons) != Q_WRP(q, prod)) &&
		(Q_IDX(q, q->cons) <= Q_IDX(q, prod)));
}

static void ummu_queue_sync_cons_out(struct ummu_queue *q)
{
	/*
	 * Ensure that all CPU accesses (reads and writes) to the queue
	 * are complete before we update the cons pointer.
	 */
	__iomb();
	writel_relaxed(q->llq.cons, q->cons_reg);
}

void ummu_queue_sync_cons_ovf(struct ummu_queue *q)
{
	struct ummu_ll_queue *llq = &q->llq;

	if (likely(Q_OVF(llq->prod) == Q_OVF(llq->cons)))
		return;

	llq->cons = Q_OVF(llq->prod) | Q_WRP(llq, llq->cons) |
		    Q_IDX(llq, llq->cons);

	ummu_queue_sync_cons_out(q);
}

static void ummu_queue_inc_cons(struct ummu_ll_queue *q)
{
	u32 cons = (Q_WRP(q, q->cons) | Q_IDX(q, q->cons)) + 1;

	q->cons = Q_OVF(q->cons) | Q_WRP(q, cons) | Q_IDX(q, cons);
}

int ummu_queue_sync_prod_in(struct ummu_queue *q)
{
	u32 prod;
	int ret = 0;

	prod = readl(q->prod_reg);
	if (Q_OVF(prod) != Q_OVF(q->llq.prod))
		ret = -EOVERFLOW;

	q->llq.prod = prod;

	return ret;
}

static u32 ummu_queue_inc_prod_n(struct ummu_ll_queue *q, int n)
{
	u32 prod = (Q_WRP(q, q->prod) | Q_IDX(q, q->prod)) + n;

	return Q_OVF(q->prod) | Q_WRP(q, prod) | Q_IDX(q, prod);
}

static void ummu_queue_poll_init(struct ummu_device *ummu,
			    struct ummu_queue_poll *qp)
{
	qp->delay = 1;
	qp->spin_cnt = 0;
	qp->wfe = !!(ummu->cap.features & UMMU_FEAT_SEV);
	qp->timeout = ktime_add_us(ktime_get(), UMMU_QUE_POLL_TIMEOUT_US);
}

static int ummu_queue_poll(struct ummu_queue_poll *qp)
{
	if (ktime_compare(ktime_get(), qp->timeout) > 0)
		return -ETIMEDOUT;

	if (qp->wfe) {
		wfe();
	} else if (++qp->spin_cnt < UMMU_POLL_SPIN_COUNT) {
		cpu_relax();
	} else {
		udelay(qp->delay);
		qp->delay *= 2; /* multiply the delay by 2 */
		qp->spin_cnt = 0;
	}

	return 0;
}

void ummu_queue_write(__le64 *dst, u64 *src, size_t n_dwords)
{
	size_t i;

	for (i = 0; i < n_dwords; ++i)
		*dst++ = cpu_to_le64(*src++);
}

void ummu_queue_read(u64 *dst, __le64 *src, size_t n_dwords)
{
	size_t i;

	for (i = 0; i < n_dwords; ++i)
		*dst++ = le64_to_cpu(*src++);
}

int ummu_queue_remove_raw(struct ummu_queue *queue, u64 *ent)
{
	if (ummu_queue_empty(&queue->llq))
		return -EAGAIN;

	ummu_queue_read(ent, Q_ENT(queue, queue->llq.cons), queue->ent_dwords);
	ummu_queue_inc_cons(&queue->llq);
	ummu_queue_sync_cons_out(queue);

	return 0;
}

static void ummu_device_free_queue(struct ummu_queue *q)
{
	size_t qsz;

	if (!q->base)
		return;

	qsz = ENTRY_DWORDS_TO_SIZE((1 << q->llq.log2size) * q->ent_dwords);
	free_pages((unsigned long)q->base, get_order(qsz));
	q->base = NULL;
}

void ummu_device_free_mcmdq(struct ummu_device *ummu)
{
	struct ummu_mcmdq *mcmdq;
	int cpu;

	if (!ummu->mcmdq || !ummu->nr_mcmdq)
		return;

	for_each_possible_cpu(cpu) {
		mcmdq = *per_cpu_ptr(ummu->mcmdq, cpu);
		if (!mcmdq || !mcmdq->q.base)
			continue;

		ummu_device_free_queue(&mcmdq->q);
	}
}

static int ummu_common_init_queue(struct ummu_device *ummu,
				  struct ummu_queue *q, size_t dwords)
{
	struct page *page = NULL;
	size_t qsz;

	q->base = NULL;
	do {
		qsz = ENTRY_DWORDS_TO_SIZE((1 << q->llq.log2size) * dwords);
		if (get_order(qsz) <= MAX_ORDER) {
			page = alloc_pages_node(dev_to_node(ummu->dev),
						UMMU_GFP(GFP_KERNEL) | __GFP_ZERO,
						get_order(qsz));
			if (page)
				q->base = (__le64 *)page_address(page);
		}

		q->llq.log2size--;
	} while (!q->base && qsz > PAGE_SIZE);

	/* confirm right log2size after the loop */
	q->llq.log2size++;

	if (!q->base) {
		dev_err(ummu->dev,
			"failed to allocate queue (0x%zx bytes)\n", qsz);
		return -ENOMEM;
	}

	q->base_pa = virt_to_phys(q->base);
	q->ent_dwords = dwords;
	q->q_base = Q_BASE_RWA;
	q->q_base |= q->base_pa & Q_BASE_ADDR_MASK;
	q->q_base |= FIELD_PREP(Q_BASE_LOG2SIZE, q->llq.log2size);
	q->llq.prod = q->llq.cons = 0;

	return 0;
}

static int ummu_mcmdq_allocate(struct ummu_device *ummu)
{
	struct ummu_mcmdq __percpu *mcmdqs;
	struct ummu_mcmdq *mcmdq;
	u32 cpu, host_cpu;

	mcmdqs = devm_alloc_percpu(ummu->dev, *mcmdq);
	if (!mcmdqs)
		return -ENOMEM;

	/* A core requires at most one ECMDQ */
	if (num_possible_cpus() < ummu->nr_mcmdq)
		ummu->nr_mcmdq = num_possible_cpus();

	for_each_possible_cpu(cpu) {
		if (cpu < ummu->nr_mcmdq) {
			mcmdq = per_cpu_ptr(mcmdqs, cpu);
			mcmdq->configured = 0;
		} else {
			host_cpu = cpu % ummu->nr_mcmdq;
			mcmdq = per_cpu_ptr(mcmdqs, host_cpu);
			mcmdq->shared = 1;
		}
		mcmdq->q.base = NULL;
		*per_cpu_ptr(ummu->mcmdq, cpu) = mcmdq;
	}

	return 0;
}

static int ummu_mcmdq_cfg_para(struct ummu_device *ummu,
			       struct ummu_mcmdq *mcmdq)
{
	atomic_long_t *bitmap;

	mcmdq->mcmdq_prod = MCMDQ_PROD_EN;

	atomic_set(&mcmdq->owner_prod, 0);
	rwlock_init(&mcmdq->mcmdq_lock);

	bitmap = (atomic_long_t *)devm_bitmap_zalloc(
		ummu->dev, 1UL << mcmdq->q.llq.log2size, GFP_KERNEL);
	if (!bitmap) {
		dev_err(ummu->dev, "failed to zalloc mcmdq bitmap\n");
		return -ENOMEM;
	}
	mcmdq->valid_map = bitmap;

	return 0;
}

static int ummu_mcmdq_init(struct ummu_device *ummu)
{
	struct ummu_mcmdq *mcmdq;
	u64 base_addr = 0;
	u32 log2size;
	int cpu, ret;

	if (ummu->cap.options & UMMU_OPT_ONE_MCMDQ) {
		ummu->nr_mcmdq = 1;
		log2size = ummu->cap.mcmdq_log2size;
	} else {
		ummu->nr_mcmdq = 1UL << ummu->cap.mcmdq_log2num;
		if (ummu->cap.options & UMMU_OPT_MCMDQ_DECREASE)
			ummu->nr_mcmdq -= 1;
		log2size = MCMDQ_MAX_SZ_SHIFT + order_base_2(
				num_possible_cpus() / ummu->nr_mcmdq);
	}

	ummu->mcmdq = devm_alloc_percpu(ummu->dev, struct ummu_mcmdq *);
	if (!ummu->mcmdq) {
		dev_err(ummu->dev, "alloc mcmdq ptr failed\n");
		goto err;
	}

	ret = ummu_mcmdq_allocate(ummu);
	if (ret) {
		dev_err(ummu->dev, "mcmdq allocate failed\n");
		goto err;
	}

	for_each_possible_cpu(cpu) {
		mcmdq = *per_cpu_ptr(ummu->mcmdq, cpu);
		/* prevent repeated init when it is shared to multiple CPUs. */
		if (!mcmdq || mcmdq->mcmdq_prod == MCMDQ_PROD_EN)
			continue;

		mcmdq->q.llq.log2size = log2size;
		mcmdq->base = ummu->base + UMMU_MCMDQ_OFFSET + base_addr;
		mcmdq->q.prod_reg = (u32 *)(mcmdq->base + MCMDQ_PROD_OFFSET);
		mcmdq->q.cons_reg = (u32 *)(mcmdq->base + MCMDQ_CONS_OFFSET);
		ret = ummu_common_init_queue(ummu, &mcmdq->q, MCMDQ_ENT_DWORDS);
		if (ret)
			goto free_q;
		ret = ummu_mcmdq_cfg_para(ummu, mcmdq);
		if (ret)
			goto free_q;

		base_addr += MCMDQ_ENT_SIZE;
	}

	return 0;

free_q:
	ummu_device_free_mcmdq(ummu);
err:
	ummu->nr_mcmdq = 0;
	return -ENOMEM;
}

static int ummu_write_mcmdq_regs(struct ummu_device *ummu)
{
	struct ummu_mcmdq *mcmdq;
	struct ummu_queue *q;
	int i = 0, ret;
	u32 cpu;
	u32 reg;

	if (unlikely(!ummu->nr_mcmdq)) {
		dev_err(ummu->dev, "have not mcmdq resource.\n");
		return -EINVAL;
	}

	for_each_possible_cpu(cpu) {
		mcmdq = *per_cpu_ptr(ummu->mcmdq, cpu);
		if (mcmdq->configured == 1)
			continue;

		q = &mcmdq->q;
		i++;
		if (WARN_ON(q->llq.prod != q->llq.cons)) {
			q->llq.prod = 0;
			q->llq.cons = 0;
		}
		/*
		 * In kdump kernel, the mcmdq should be turned off first to
		 * prevent  "CMD_SYNC timeout" problem.
		 */
		reg = readl(q->prod_reg);
		if (reg & MCMDQ_PROD_EN) {
			writel(reg & ~MCMDQ_PROD_EN, q->prod_reg);
			ret = readl_relaxed_poll_timeout(q->cons_reg, reg,
						!(reg & MCMDQ_EN_RESP), 1,
						UMMU_CONS_POLL_TIMEOUT_US);
			if (ret) {
				dev_warn(ummu->dev,
					 "mcmdq[%d] disable failed\n", i);
				mcmdq->configured = 0;
				return ret;
			}
		}

		/* close mcmdq_base write protection */
		writel_relaxed(q->llq.prod, q->prod_reg);
		writel_relaxed(q->llq.cons, q->cons_reg);
		writeq_relaxed(q->q_base, mcmdq->base);

		/* enable mcmdq and open write protection */
		writel_relaxed(MCMDQ_PROD_EN | q->llq.prod, mcmdq->q.prod_reg);
		ret = readl_relaxed_poll_timeout(mcmdq->q.cons_reg, reg,
						 reg & MCMDQ_EN_RESP, 1,
						 UMMU_CONS_POLL_TIMEOUT_US);
		if (ret) {
			dev_err(ummu->dev, "prod_reg write timeout ret = %d.\n",
				ret);
			return ret;
		}
		mcmdq->configured = 1;
	}

	return 0;
}

int ummu_device_mcmdq_init_cfg(struct ummu_device *ummu)
{
	int ret;

	if (ummu->impl_ops && ummu->impl_ops->mcmdq_cfg) {
		ret = ummu->impl_ops->mcmdq_cfg(ummu);
		if (ret)
			return ret;
	}

	return ummu_write_mcmdq_regs(ummu);
}

int ummu_write_evtq_regs(struct ummu_device *ummu)
{
	u32 cr0 = readl_relaxed(ummu->base + UMMU_CR0);
	struct ummu_queue *q = &ummu->evtq.q;

	/* evtq disabled in function ummu_device_disable */
	writeq_relaxed(q->q_base, ummu->base + UMMU_EVTQ_OFFSET);

	writel_relaxed(q->llq.prod, ummu->base + UMMU_EVTQ_PROD_OFFSET);
	writel_relaxed(q->llq.cons, ummu->base + UMMU_EVTQ_CONS_OFFSET);

	cr0 |= CR0_EVENTQ_EN;

	return ummu_write_reg_sync(ummu, cr0, UMMU_CR0, UMMU_CR0ACK);
}

void ummu_device_free_evtq(struct ummu_device *ummu)
{
	ummu_device_free_queue(&ummu->evtq.q);
}

static int ummu_evtq_init(struct ummu_device *ummu)
{
	struct ummu_queue *q = &ummu->evtq.q;
	int ret;

	q->llq.log2size = min(EVTQ_MAX_SZ_SHIFT, ummu->cap.evtq_log2size);
	q->prod_reg = (u32 *)(ummu->base + UMMU_EVTQ_PROD_OFFSET);
	q->cons_reg = (u32 *)(ummu->base + UMMU_EVTQ_CONS_OFFSET);
	ret = ummu_common_init_queue(ummu, q, EVTQ_ENT_DWORDS);
	if (ret)
		return ret;

	if ((ummu->cap.features & UMMU_FEAT_SVA) &&
	    (ummu->cap.features & UMMU_FEAT_STALLS)) {
		ret =  ummu_iopf_queue_alloc(ummu);
		if (ret) {
			ummu_device_free_queue(q);
			return ret;
		}
	}

	return 0;
}

int ummu_init_queues(struct ummu_device *ummu)
{
	if (!(ummu->cap.features & UMMU_FEAT_MCMDQ) ||
	    !(ummu->cap.features & UMMU_FEAT_EVENTQ))
		return -EOPNOTSUPP;

	if (ummu_mcmdq_init(ummu))
		return -ENOMEM;

	if (ummu_evtq_init(ummu))
		return -ENOMEM;

	return 0;
}

#define ummu_mcmdq_exclusive_trylock_irqsave(mcmdq, flags)                   \
	({                                                                   \
		bool __ret;                                                  \
		local_irq_save(flags);                                       \
		__ret = !atomic_cmpxchg_relaxed(&(mcmdq)->lock, 0, INT_MIN); \
		if (!__ret)                                                  \
			local_irq_restore(flags);                            \
		__ret;                                                       \
	})

#define ummu_mcmdq_exclusive_unlock_irqrestore(mcmdq, flags) \
	({                                                   \
		atomic_set_release(&(mcmdq)->lock, 0);       \
		local_irq_restore(flags);                    \
	})

/* Wait for the command queue to become non-full */
static int ummu_mcmdq_poll_until_not_full(struct ummu_device *ummu,
				   struct ummu_mcmdq *mcmdq,
				   struct ummu_ll_queue *llq)
{
	struct ummu_queue_poll qp;
	unsigned long flags;
	int ret = 0;

	/*
	 * Try to update our copy of cons by grabbing exclusive mcmdq access. If
	 * that fails, spin until somebody else updates it for us.
	 */
	if (ummu_mcmdq_exclusive_trylock_irqsave(mcmdq, flags)) {
		WRITE_ONCE(mcmdq->q.llq.cons, readl_relaxed(mcmdq->q.cons_reg));
		ummu_mcmdq_exclusive_unlock_irqrestore(mcmdq, flags);
		llq->val = READ_ONCE(mcmdq->q.llq.val);
		return 0;
	}

	ummu_queue_poll_init(ummu, &qp);
	do {
		llq->val = READ_ONCE(mcmdq->q.llq.val);
		if (!ummu_queue_full(llq))
			break;

		ret = ummu_queue_poll(&qp);
	} while (!ret);

	return ret;
}

/*
 * The command queue is locked.
 * This is a private form of rwlock with the following main variations:
 *
 * - The UNLOCK routine is supplemented by shared_tryunlock(), where
 * If the caller appears to be the last lock holder (yes, this is
 * All successful UNLOCK routines have RELEASE semantics.
 *
 * - The only LOCK routines are exclusive_trylock() and shared_lock().
 * Neither has barrier semantics, but only provides control.
 * Dependency.
 */
static void ummu_mcmdq_shared_lock(struct ummu_mcmdq *mcmdq)
{
	int val;

	/*
	 * We can try to avoid the cmpxchg() loop by simply incrementing the
	 * lock counter. When held in exclusive state, the lock counter is set
	 * to INT_MIN so these increments won't hurt as the value will remain
	 * negative.
	 */
	if (atomic_fetch_inc_relaxed(&mcmdq->lock) >= 0)
		return;

	do {
		val = atomic_cond_read_relaxed(&mcmdq->lock, VAL >= 0);
	} while (atomic_cmpxchg_relaxed(&mcmdq->lock, val, val + 1) != val);
}

static void ummu_mcmdq_shared_unlock(struct ummu_mcmdq *mcmdq)
{
	(void)atomic_dec_return_release(&mcmdq->lock);
}

static bool ummu_mcmdq_shared_tryunlock(struct ummu_mcmdq *mcmdq)
{
	if (atomic_read(&mcmdq->lock) == 1)
		return false;

	ummu_mcmdq_shared_unlock(mcmdq);

	return true;
}

static int ummu_mcmdq_build_nop_cmd(u64 *cmd, struct ummu_mcmdq_ent *ent)
{
	cmd[0] |= FIELD_PREP(CMD_NULL_OP_SUB_OP, ent->null_op.sub_op);
	switch (ent->null_op.sub_op) {
	case SUB_CMD_NULL_CHECK_PA_CONTINUITY:
		cmd[0] |= FIELD_PREP(SUB_OP_CHECK_PA_CONTI_0_RESULT,
				     ent->null_op.check_pa_conti.result);
		cmd[0] |= ent->null_op.check_pa_conti.flag ?
			  SUB_OP_CHECK_PA_CONTI_0_FLAG : 0;
		cmd[0] |= FIELD_PREP(SUB_OP_CHECK_PA_CONTI_0_SIZE,
				     ent->null_op.check_pa_conti.size_order);
		cmd[0] |= FIELD_PREP(SUB_OP_CHECK_PA_CONTI_0_ID,
				     ent->null_op.check_pa_conti.id);
		cmd[1] |= SUB_OP_CHECK_PA_CONTI_1_ADDR &
			  ent->null_op.check_pa_conti.addr;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int ummu_mcmdq_build_cmd(struct ummu_device *ummu, u64 *cmd,
			 struct ummu_mcmdq_ent *ent)
{
	memset(cmd, 0, 1 << MCMDQ_ENT_SZ_SHIFT);
	cmd[0] |= FIELD_PREP(CMD_0_OP, ent->opcode);

	/* build cmd method for different cmds */
	switch (ent->opcode) {
	case CMD_SYNC:
		if (ent->sync.msi_addr) {
			cmd[0] |= FIELD_PREP(CMD_SYNC_0_CM, CMD_SYNC_0_CM_IRQ);
			cmd[1] |= ent->sync.msi_addr & CMD_SYNC_1_MSIADDR;
		} else if (ent->sync.support_sev) {
			cmd[0] |= FIELD_PREP(CMD_SYNC_0_CM, CMD_SYNC_0_CM_SEV);
		} else {
			cmd[0] |= FIELD_PREP(CMD_SYNC_0_CM, CMD_SYNC_0_CM_NONE);
		}
		cmd[0] |= FIELD_PREP(CMD_SYNC_0_MSISH, UMMU_SH_ISH);
		cmd[0] |= FIELD_PREP(CMD_SYNC_0_MSIATTR, UMMU_MEMATTR_OIWB);
		break;
	case CMD_STALL_RESUME:
		cmd[0] |= ent->stall_resume.dsec ? CMD_STALL_0_DSEC : 0;
		cmd[0] |= ent->stall_resume.retry ? CMD_STALL_0_RETRY : 0;
		cmd[0] |= ent->stall_resume.abort ? CMD_STALL_0_ABORT : 0;
		cmd[1] |= FIELD_PREP(CMD_STALL_1_TAG,  ent->stall_resume.tag);
		cmd[2] |= FIELD_PREP(CMD_STALL_2_TECT_TAG,
				     ent->stall_resume.tect_tag);
		break;
	case CMD_STALL_TERM:
		cmd[2] |= FIELD_PREP(CMD_STALL_2_TECT_TAG, ent->stall_resume.tect_tag);
		break;
	case CMD_PREFET_CFG:
		cmd[0] |= ent->prefet.tkv ? CMD_PREFET_0_TKV : 0;
		cmd[0] |= FIELD_PREP(CMD_PREFET_0_TID, ent->prefet.tid);
		cmd[2] |= FIELD_PREP(CMD_PREFET_2_DEID_0, ent->prefet.deid_0);
		cmd[2] |= FIELD_PREP(CMD_PREFET_2_DEID_1, ent->prefet.deid_1);
		cmd[3] |= FIELD_PREP(CMD_PREFET_3_DEID_0, ent->prefet.deid_2);
		cmd[3] |= FIELD_PREP(CMD_PREFET_3_DEID_1, ent->prefet.deid_3);
		break;
	case CMD_CFGI_TECT:
		cmd[0] |= ent->cfgi.leaf ? CMD_CFGI_0_LEAF : 0;
		cmd[2] |= FIELD_PREP(CMD_CFGI_2_DEID_0, ent->cfgi.deid_0);
		cmd[2] |= FIELD_PREP(CMD_CFGI_2_DEID_1, ent->cfgi.deid_1);
		cmd[3] |= FIELD_PREP(CMD_CFGI_3_DEID_0, ent->cfgi.deid_2);
		cmd[3] |= FIELD_PREP(CMD_CFGI_3_DEID_1, ent->cfgi.deid_3);
		break;
	case CMD_CFGI_TECT_RANGE:
		cmd[0] |= FIELD_PREP(CMD_CFGI_0_RANGE, ent->cfgi.range);
		cmd[2] |= FIELD_PREP(CMD_CFGI_2_DEID_0, ent->cfgi.deid_0);
		cmd[2] |= FIELD_PREP(CMD_CFGI_2_DEID_1, ent->cfgi.deid_1);
		cmd[3] |= FIELD_PREP(CMD_CFGI_3_DEID_0, ent->cfgi.deid_2);
		cmd[3] |= FIELD_PREP(CMD_CFGI_3_DEID_1, ent->cfgi.deid_3);
		break;
	case CMD_CFGI_TCT:
		cmd[0] |= ent->cfgi.leaf ? CMD_CFGI_0_LEAF : 0;
		cmd[0] |= FIELD_PREP(CMD_CFGI_0_TID, ent->cfgi.tid);
		cmd[2] |= FIELD_PREP(CMD_CFGI_2_DEID_0, ent->cfgi.deid_0);
		cmd[2] |= FIELD_PREP(CMD_CFGI_2_DEID_1, ent->cfgi.deid_1);
		cmd[3] |= FIELD_PREP(CMD_CFGI_3_DEID_0, ent->cfgi.deid_2);
		cmd[3] |= FIELD_PREP(CMD_CFGI_3_DEID_1, ent->cfgi.deid_3);
		break;
	case CMD_CFGI_TCT_ALL:
		cmd[0] |= ent->cfgi.leaf ? CMD_CFGI_0_LEAF : 0;
		cmd[0] |= FIELD_PREP(CMD_CFGI_0_TID, ent->cfgi.tid);
		cmd[2] |= FIELD_PREP(CMD_CFGI_2_DEID_0, ent->cfgi.deid_0);
		cmd[2] |= FIELD_PREP(CMD_CFGI_2_DEID_1, ent->cfgi.deid_1);
		cmd[3] |= FIELD_PREP(CMD_CFGI_3_DEID_0, ent->cfgi.deid_2);
		cmd[3] |= FIELD_PREP(CMD_CFGI_3_DEID_1, ent->cfgi.deid_3);
		break;
	case CMD_PLBI_OS_EID:
		cmd[2] |= FIELD_PREP(CMD_PLBI_2_TECTE_TAG, ent->plbi.tecte_tag);
		break;
	case CMD_PLBI_OS_EIDTID:
		cmd[0] |= FIELD_PREP(CMD_PLBI_0_TID, ent->plbi.tid);
		cmd[2] |= FIELD_PREP(CMD_PLBI_2_TECTE_TAG, ent->plbi.tecte_tag);
		break;
	case CMD_PLBI_OS_VA:
		cmd[0] |= FIELD_PREP(CMD_PLBI_0_TID, ent->plbi.tid);
		cmd[0] |= FIELD_PREP(CMD_PLBI_0_RANGE, ent->plbi.range);
		cmd[1] |= ent->plbi.addr & CMD_PLBI_1_ADDR_MASK;
		cmd[2] |= FIELD_PREP(CMD_PLBI_2_TECTE_TAG, ent->plbi.tecte_tag);
		break;
	case CMD_TLBI_OS_ALL:
		cmd[2] |= FIELD_PREP(CMD_TLBI_2_TECTE_TAG, ent->tlbi.tect_tag);
		break;
	case CMD_TLBI_OS_TID:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_TOKEN_ID, ent->tlbi.tid);
		cmd[2] |= FIELD_PREP(CMD_TLBI_2_TECTE_TAG, ent->tlbi.tect_tag);
		break;
	case CMD_TLBI_OS_VA:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_TOKEN_ID, ent->tlbi.tid);
		fallthrough;
	case CMD_TLBI_OS_VAA:
		cmd[2] |= FIELD_PREP(CMD_TLBI_2_TECTE_TAG, ent->tlbi.tect_tag);
		cmd[0] |= ent->tlbi.leaf ? CMD_TLBI_0_LEAF : 0;
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_NUM, ent->tlbi.num);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_SCALE, ent->tlbi.scale);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_TL, ent->tlbi.tl);
		cmd[1] |= FIELD_PREP(CMD_TLBI_1_GS, ent->tlbi.gs);
		cmd[1] |= ent->tlbi.addr & CMD_TLBI_1_VA_MASK;
		break;
	case CMD_TLBI_HYP_TID:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_TOKEN_ID, ent->tlbi.tid);
		break;
	case CMD_TLBI_HYP_VA:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_TOKEN_ID, ent->tlbi.tid);
		fallthrough;
	case CMD_TLBI_HYP_VAA:
		cmd[0] |= ent->tlbi.leaf ? CMD_TLBI_0_LEAF : 0;
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_NUM, ent->tlbi.num);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_SCALE, ent->tlbi.scale);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_TL, ent->tlbi.tl);
		cmd[1] |= FIELD_PREP(CMD_TLBI_1_GS, ent->tlbi.gs);
		cmd[1] |= ent->tlbi.addr & CMD_TLBI_1_VA_MASK;
		break;
	case CMD_TLBI_S1S2_VMALL:
		cmd[2] |= FIELD_PREP(CMD_TLBI_2_TECTE_TAG, ent->tlbi.tect_tag);
		break;
	case CMD_TLBI_S2_IPA:
		cmd[2] |= FIELD_PREP(CMD_TLBI_2_TECTE_TAG, ent->tlbi.tect_tag);
		cmd[0] |= ent->tlbi.leaf ? CMD_TLBI_0_LEAF : 0;
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_NUM, ent->tlbi.num);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_SCALE, ent->tlbi.scale);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_TL, ent->tlbi.tl);
		cmd[1] |= FIELD_PREP(CMD_TLBI_1_GS, ent->tlbi.gs);
		cmd[1] |= ent->tlbi.addr & CMD_TLBI_1_VA_MASK;
		break;
	case CMD_TLBI_HYP_ALL:
	case CMD_TLBI_NS_OS_ALL:
		break;
	case CMD_CREATE_KVTBL:
		cmd[0] |= ent->create_kvtbl.evt_en ?
			   CMD_CREATE_KVTBL0_EVT_EN : 0;
		cmd[0] |= FIELD_PREP(CMD_CREATE_KVTBL0_TAG_MASK,
				     ent->create_kvtbl.tecte_tag);
		cmd[0] |= FIELD_PREP(CMD_CREATE_KVTBL0_KV_INDEX_MASK,
				     ent->create_kvtbl.kv_index);
		cmd[1] |= ent->create_kvtbl.tect_base_addr &
			  CMD_CREATE_KVTBL1_ADDR_MASK;
		cmd[2] |= FIELD_PREP(CMD_CREATE_KVTBL2_EID_LOW,
				     ent->create_kvtbl.eid_low);
		cmd[3] |= FIELD_PREP(CMD_CREATE_KVTBL3_EID_HIGH,
				     ent->create_kvtbl.eid_high);
		break;
	case CMD_DELETE_KVTBL:
		cmd[0] |= ent->delete_kvtbl.evt_en ?
			   CMD_DELETE_KVTBL0_EVT_EN : 0;
		cmd[0] |= FIELD_PREP(CMD_DELETE_KVTBL0_TAG_MASK,
				     ent->delete_kvtbl.tecte_tag);
		cmd[0] |= FIELD_PREP(CMD_DELETE_KVTBL0_KV_INDEX_MASK,
				     ent->delete_kvtbl.kv_index);
		cmd[2] |= FIELD_PREP(CMD_DELETE_KVTBL2_EID_LOW,
				     ent->delete_kvtbl.eid_low);
		cmd[3] |= FIELD_PREP(CMD_DELETE_KVTBL3_EID_HIGH,
				     ent->delete_kvtbl.eid_high);
		break;
	case CMD_TLBI_OS_ALL_U:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_VMID, ent->tlbi.vmid);
		break;
	case CMD_TLBI_OS_ASID_U:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_ASID, ent->tlbi.asid);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_VMID, ent->tlbi.vmid);
		break;
	case CMD_TLBI_OS_VA_U:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_ASID, ent->tlbi.asid);
		fallthrough;
	case CMD_TLBI_OS_VAA_U:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_VMID, ent->tlbi.vmid);
		cmd[0] |= ent->tlbi.leaf ? CMD_TLBI_0_LEAF : 0;
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_NUM, ent->tlbi.num);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_SCALE, ent->tlbi.scale);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_TL, ent->tlbi.tl);
		cmd[1] |= FIELD_PREP(CMD_TLBI_1_GS, ent->tlbi.gs);
		cmd[1] |= ent->tlbi.addr & CMD_TLBI_1_VA_MASK;
		break;
	case CMD_TLBI_HYP_ASID_U:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_ASID, ent->tlbi.asid);
		break;
	case CMD_TLBI_HYP_VA_U:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_ASID, ent->tlbi.asid);
		cmd[0] |= ent->tlbi.leaf ? CMD_TLBI_0_LEAF : 0;
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_NUM, ent->tlbi.num);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_SCALE, ent->tlbi.scale);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_TL, ent->tlbi.tl);
		cmd[1] |= FIELD_PREP(CMD_TLBI_1_GS, ent->tlbi.gs);
		cmd[1] |= ent->tlbi.addr & CMD_TLBI_1_VA_MASK;
		break;
	case CMD_TLBI_S1S2_VMALL_U:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_VMID, ent->tlbi.vmid);
		break;
	case CMD_TLBI_S2_IPA_U:
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_VMID, ent->tlbi.vmid);
		cmd[0] |= ent->tlbi.leaf ? CMD_TLBI_0_LEAF : 0;
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_NUM, ent->tlbi.num);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_SCALE, ent->tlbi.scale);
		cmd[0] |= FIELD_PREP(CMD_TLBI_0_TL, ent->tlbi.tl);
		cmd[1] |= FIELD_PREP(CMD_TLBI_1_GS, ent->tlbi.gs);
		cmd[1] |= ent->tlbi.addr & CMD_TLBI_1_IPA_MASK;
		break;
	case CMD_NULL_OP:
		return ummu_mcmdq_build_nop_cmd(cmd, ent);
	case CMD_PLBI_OS_N:
		cmd[0] |= FIELD_PREP(CMD_PLBI_0_TID, ent->plbi_free_bit.tid);
		cmd[1] |= FIELD_PREP(CMD_PLBI_1_NEXT_LEVEL_INDEX_MASK,
				     ent->plbi_free_bit.next_lvl_idx);
		cmd[1] |= FIELD_PREP(CMD_PLBI_1_NEXT_LEVEL_OFFSET_MASK,
				     ent->plbi_free_bit.next_lvl_offset);
		cmd[2] |= FIELD_PREP(CMD_TLBI_2_TECTE_TAG, ent->plbi_free_bit.tecte_tag);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/*
 * Command queue insertion.
 * This process became cumbersome as we aimed to achieve scalability
 * due to the shared queue among all CPUs in the system.
 * If you desire a combination of size concurrency, dependency order,
 * and loose atoms, then you will absolutely adore this monstrous solution.
 * The fundamental concept is to divide the queue into command ranges
 * owned by each CPU. The owner may not have authored all the commands
 * themselves but assumes responsibility for advancing the hardware product
 * pointer under certain circumstances: when it's time. The algorithm can be
 * summarized as follows:
 * 1. Allocate space within the queue while also determining if another CPU
 *     currently owns the head of the queue or if we are its rightful owners.
 * 2. Write our commands into the allocated slot within the queue.
 * 3. Mark our slot as valid in ummu_mcmdq.valid_map.
 * 4. If we are indeed the owner:
 *    A. Wait for completion by any previous owner.
 *    B. Declare that there is no current owner for this range,
 *       indicating our responsibility for publishing it.
 *    C. Await execution of all orders within our possession.
 *    D. Advance the hardware product pointer.
 *    E. Notify subsequent hosts that we have completed our tasks.
 * 5. If we insert CMD_SYNC (whether or not we are its owner),
 *     then we must persist with it until completion:
 *    A. If MSI is available, UMMU can write back to CMD_SYNC and
 *       clear its first 4 bytes.
 *    B. Otherwise, rotate and wait until the hardware cons pointer points
 *       beyond our command.
 * The devil lies in these intricate details-particularly regarding locking
 * mechanisms-to ensure complete synchronization and efficient utilization of
 * space within the queue before deeming it full.
 */
static void ummu_mcmdq_build_sync_cmd(u64 *cmd, struct ummu_device *ummu,
				      struct ummu_queue *q, u32 prod)
{
	struct ummu_mcmdq_ent ent = {
		.opcode = CMD_SYNC,
	};

	/*
	 * Beware that Hi16xx adds an extra 32 bits of goodness to its MSI
	 * payload, so the write will zero the entire command on that platform.
	 */
	if (ummu->cap.options & UMMU_OPT_MSIPOLL)
		ent.sync.msi_addr = q->base_pa + Q_IDX(&q->llq, prod) *
						ENTRY_DWORDS_TO_SIZE(q->ent_dwords);
	ent.sync.support_sev = !!(ummu->cap.features & UMMU_FEAT_SEV);
	(void)ummu_mcmdq_build_cmd(ummu, cmd, &ent);
}

static void ummu_mcmdq_poll_set_valid_map(struct ummu_mcmdq *mcmdq, u32 sprod, u32 eprod, bool set)
{
	u32 swidx, sbidx, ewidx, ebidx;
	struct ummu_ll_queue llq;
	unsigned long valid;
	unsigned long mask;
	atomic_long_t *ptr;
	u32 limit;

	llq.prod = sprod;
	llq.log2size = mcmdq->q.llq.log2size;

	ewidx = BIT_WORD(Q_IDX(&llq, eprod));
	ebidx = Q_IDX(&llq, eprod) % BITS_PER_LONG;

	while (llq.prod != eprod) {
		limit = BITS_PER_LONG;
		swidx = BIT_WORD(Q_IDX(&llq, llq.prod));
		sbidx = Q_IDX(&llq, llq.prod) % BITS_PER_LONG;

		ptr = &mcmdq->valid_map[swidx];

		if ((swidx == ewidx) && (sbidx < ebidx))
			limit = ebidx;

		mask = GENMASK(limit - 1, sbidx);

		if (set) {
			atomic_long_xor(mask, ptr);
		} else { /* Poll */
			/*
			 * The valid bit is equal to the wrap bit.
			 * This means that a queue initialized to 0 is invalid,
			 * and after all elements are marked as valid, causing a rollover,
			 * all elements become invalid again.
			 */

			valid = (ULONG_MAX + !!Q_WRP(&llq, llq.prod)) & mask;
			atomic_long_cond_read_relaxed(ptr,
						      (VAL & mask) == valid);
		}

		llq.prod = ummu_queue_inc_prod_n(&llq, limit - sbidx);
	}
}

/* Mark all entries in the range [sprod, eprod) as valid */
static void ummu_mcmdq_set_valid_map(struct ummu_mcmdq *mcmdq, u32 sprod,
				     u32 eprod)
{
	ummu_mcmdq_poll_set_valid_map(mcmdq, sprod, eprod, true);
}

/* Wait for all entries in the range [sprod, eprod) to become valid */
static void ummu_mcmdq_poll_valid_map(struct ummu_mcmdq *mcmdq, u32 sprod,
				      u32 eprod)
{
	ummu_mcmdq_poll_set_valid_map(mcmdq, sprod, eprod, false);
}

/*
 * Wait until the UMMU signals a CMD_SYNC completion MSI.
 */
static int ummu_mcmdq_poll_until_msi(struct ummu_device *ummu,
				     struct ummu_mcmdq *mcmdq,
				     struct ummu_ll_queue *llq)
{
	u32 *cmd = (u32 *)(Q_ENT(&mcmdq->q, llq->prod));
	struct ummu_queue_poll qp;
	int ret = 0;

	ummu_queue_poll_init(ummu, &qp);

	/*
	 * The MSI won't generate an event, since it's being written back
	 * into the command queue.
	 */
	qp.wfe = false;
	smp_cond_load_relaxed(cmd, !VAL || (ret = ummu_queue_poll(&qp)));
	llq->cons = ret ? readl(mcmdq->q.cons_reg) : ummu_queue_inc_prod_n(llq, 1);

	return ret;
}

/*
 * Wait until the UMMU cons index passes llq->prod.
 */
static int ummu_mcmdq_poll_until_consumed(struct ummu_device *ummu,
					  struct ummu_mcmdq *mcmdq,
					  struct ummu_ll_queue *llq)
{
	struct ummu_queue_poll qp;
	u32 prod = llq->prod;
	int ret = 0;

	ummu_queue_poll_init(ummu, &qp);
	llq->val = READ_ONCE(mcmdq->q.llq.val);
	do {
		if (ummu_queue_consumed(llq, prod))
			break;

		ret = ummu_queue_poll(&qp);

		/*
		 * This needs to be a readl() so that our subsequent call
		 * to ummu_mcmdq_shared_tryunlock() can fail accurately.
		 *
		 * Specifically, we need to ensure that we observe all
		 * shared_lock()s by other CMD_SYNCs that share our owner,
		 * so that a failing call to tryunlock() means that we're
		 * the last one out and therefore we can safely advance
		 * mcmdq->q.llq.cons. Roughly speaking:
		 */
		llq->cons = readl(mcmdq->q.cons_reg);
	} while (!ret);

	return ret;
}

static int ummu_mcmdq_poll_until_sync(struct ummu_device *ummu,
				      struct ummu_mcmdq *mcmdq,
				      struct ummu_ll_queue *llq)
{
	if (ummu->cap.options & UMMU_OPT_MSIPOLL)
		return ummu_mcmdq_poll_until_msi(ummu, mcmdq, llq);

	return ummu_mcmdq_poll_until_consumed(ummu, mcmdq, llq);
}

static void ummu_mcmdq_write_entries(struct ummu_mcmdq *mcmdq, u64 *cmds,
				     u32 prod, int n)
{
	struct ummu_ll_queue llq;
	u64 *cmd;
	int i;

	llq.prod = prod;
	llq.log2size = mcmdq->q.llq.log2size;

	for (i = 0; i < n; ++i) {
		cmd = &cmds[i * MCMDQ_ENT_DWORDS];
		prod = ummu_queue_inc_prod_n(&llq, i);
		ummu_queue_write(Q_ENT(&mcmdq->q, prod), cmd, MCMDQ_ENT_DWORDS);
	}
}

static int check_pa_continuity_nop_exec(struct ummu_queue *q, u32 prod)
{
	u64 cmd;

	cmd = (u64)le64_to_cpu(Q_ENT(q, prod));
	if (FIELD_GET(CMD_0_OP, cmd) == CMD_NULL_OP &&
	    FIELD_GET(CMD_NULL_OP_SUB_OP, cmd) ==
		      SUB_CMD_NULL_CHECK_PA_CONTINUITY) {
		if (FIELD_GET(SUB_OP_CHECK_PA_CONTI_0_RESULT, cmd))
			return -ENOSPC;
		if (FIELD_GET(SUB_OP_CHECK_PA_CONTI_0_FLAG, cmd) == 1 &&
			FIELD_GET(SUB_OP_CHECK_PA_CONTI_0_ID, cmd) != 0)
			return -ERANGE;
	}
	return 0;
}

static struct ummu_mcmdq *ummu_device_get_mcmdq(struct ummu_device *ummu,
						u64 *cmd)
{
	return *this_cpu_ptr(ummu->mcmdq);
}

static int ummu_mcmdq_exclusive_issue_cmdlist(struct ummu_device *ummu,
					      struct ummu_mcmdq *mcmdq,
					      u64 *cmds, int n, bool sync)
{
	u64 cmd_sync[MCMDQ_ENT_DWORDS], old;
	struct ummu_ll_queue llq, head;
	unsigned long flags;
	u32 prod, sprod;
	int ret = 0;

	llq.log2size = mcmdq->q.llq.log2size;
	/* 1. Allocate some space in the queue */
	local_irq_save(flags);
	llq.val = READ_ONCE(mcmdq->q.llq.val);
	do {
		while (!ummu_queue_has_space(&llq, n + (sync ? 1 : 0))) {
			local_irq_restore(flags);
			if (ummu_mcmdq_poll_until_not_full(ummu, mcmdq, &llq))
				dev_err_ratelimited(ummu->dev, "wait MCMDQ not full timeout.\n");
			local_irq_save(flags);
		}

		head.cons = llq.cons;
		head.prod = ummu_queue_inc_prod_n(&llq, n + (sync ? 1 : 0));

		old = cmpxchg_relaxed(&mcmdq->q.llq.val, llq.val, head.val);
		if (old == llq.val)
			break;

		llq.val = old;
	} while (1);
	sprod = llq.prod;

	/* 2. Write our commands into the queue */
	ummu_mcmdq_write_entries(mcmdq, cmds, llq.prod, n);
	if (sync) {
		prod = ummu_queue_inc_prod_n(&llq, n);
		ummu_mcmdq_build_sync_cmd(cmd_sync, ummu, &mcmdq->q, prod);
		ummu_queue_write(Q_ENT(&mcmdq->q, prod), cmd_sync, MCMDQ_ENT_DWORDS);
	}

	/* 3. Ensuring commands are visible first */
	dma_wmb();

	/* 4. Advance the hardware prod pointer */
	read_lock(&mcmdq->mcmdq_lock);
	writel_relaxed(head.prod | mcmdq->mcmdq_prod, mcmdq->q.prod_reg);
	read_unlock(&mcmdq->mcmdq_lock);

	/* 5. If we are inserting a CMD_SYNC, we must wait for it to complete */
	if (sync) {
		llq.prod = ummu_queue_inc_prod_n(&llq, n);
		ret = ummu_mcmdq_poll_until_sync(ummu, mcmdq, &llq);
		if (ret) {
			/*
			 * When sync times out, error handling cannot be performed more
			 * effectively and CIs need to be maintained. Therefore, continue.
			 */
			dev_err_ratelimited(ummu->dev,
				"CMD_SYNC timeout at 0x%08x [hwprod 0x%08x, hwcons 0x%08x]\n",
				llq.prod,
				readl_relaxed(mcmdq->q.prod_reg),
				readl_relaxed(mcmdq->q.cons_reg));
		}

		ret = check_pa_continuity_nop_exec(&mcmdq->q, sprod);
		/*
		 * Update mcmdq->q.llq.cons, to improve the success rate of
		 * ummu_queue_has_space() when some new commands are inserted next
		 * time.
		 */
		WRITE_ONCE(mcmdq->q.llq.cons, llq.cons);
	}

	local_irq_restore(flags);
	return ret;
}

/*
 * The actual insert function provides the following functionality for
 * sorting guarantees to callers:
 * - Prioritizing write ordering of data structures in memory
 * by ensuring a dma_wmb() before publishing any
 * command to the queue.
 * - Sorting subsequent writes to memory
 * (e.g., releasing the IOVA after CMD_SYNC is complete) through a
 * control dependency when CMD_SYNC is finished.
 * - Ensuring fully ordered command insertion, where if two CPUs
 * compete with each other to insert their own command lists, one CPU's
 * commands will always appear before any commands from another CPU.
 */
int ummu_mcmdq_issue_cmdlist(struct ummu_device *ummu, u64 *cmds,
			     int n, bool sync)
{
	struct ummu_mcmdq *mcmdq = ummu_device_get_mcmdq(ummu, cmds);
	u64 cmd_sync[MCMDQ_ENT_DWORDS];
	struct ummu_ll_queue llq, head;
	unsigned long flags;
	u32 prod, sprod;
	int ret = 0;
	bool owner;
	u64 old;

	if (unlikely(!mcmdq->shared))
		return ummu_mcmdq_exclusive_issue_cmdlist(ummu, mcmdq, cmds,
							  n, sync);

	llq.log2size = mcmdq->q.llq.log2size;

	/* 1. Allocate some space in the queue */
	local_irq_save(flags);
	llq.val = READ_ONCE(mcmdq->q.llq.val);
	do {
		while (!ummu_queue_has_space(&llq, n + (sync ? 1 : 0))) {
			local_irq_restore(flags);
			if (ummu_mcmdq_poll_until_not_full(ummu, mcmdq, &llq))
				dev_err_ratelimited(ummu->dev, "wait MCMDQ not full timeout.\n");
			local_irq_save(flags);
		}

		head.cons = llq.cons;
		head.prod = ummu_queue_inc_prod_n(&llq, n + (sync ? 1 : 0)) |
			    MCMDQ_PROD_OWNED_FLAG;

		old = cmpxchg_relaxed(&mcmdq->q.llq.val, llq.val, head.val);
		if (old == llq.val)
			break;

		llq.val = old;
	} while (1);
	owner = !(llq.prod & MCMDQ_PROD_OWNED_FLAG);
	head.prod &= ~MCMDQ_PROD_OWNED_FLAG;
	llq.prod &= ~MCMDQ_PROD_OWNED_FLAG;
	sprod = llq.prod;
	/*
	 * 2. Write our commands into the queue
	 * Dependency ordering from the cmpxchg() loop above.
	 */
	ummu_mcmdq_write_entries(mcmdq, cmds, llq.prod, n);
	if (sync) {
		prod = ummu_queue_inc_prod_n(&llq, n);
		ummu_mcmdq_build_sync_cmd(cmd_sync, ummu, &mcmdq->q, prod);
		ummu_queue_write(Q_ENT(&mcmdq->q, prod), cmd_sync, MCMDQ_ENT_DWORDS);

		/*
		 * In order to determine completion of our CMD_SYNC, we must
		 * ensure that the queue can't wrap twice without us noticing.
		 * We achieve that by taking the mcmdq lock as shared before
		 * marking our slot as valid.
		 */
		ummu_mcmdq_shared_lock(mcmdq);
	}

	/* 3. Mark our slots as valid, ensuring commands are visible first */
	dma_wmb();
	ummu_mcmdq_set_valid_map(mcmdq, llq.prod, head.prod);

	/* 4. If we are the owner, take control of the UMMU hardware */
	if (owner) {
		/* a. Wait for previous owner to finish */
		atomic_cond_read_relaxed(&mcmdq->owner_prod, VAL == llq.prod);

		/* b. Stop gathering work by clearing the owned flag */
		prod = atomic_fetch_andnot_relaxed(MCMDQ_PROD_OWNED_FLAG,
						   &mcmdq->q.llq.atomic.prod);
		prod &= ~MCMDQ_PROD_OWNED_FLAG;

		/*
		 * c. Wait for any gathered work to be written to the queue.
		 * Note that we read our own entries so that we have the control
		 * dependency required by (d).
		 */
		ummu_mcmdq_poll_valid_map(mcmdq, llq.prod, prod);

		/*
		 * d. Advance the hardware prod pointer
		 * Control dependency ordering from the entries becoming valid.
		 */
		read_lock(&mcmdq->mcmdq_lock);
		writel_relaxed(prod | mcmdq->mcmdq_prod, mcmdq->q.prod_reg);
		read_unlock(&mcmdq->mcmdq_lock);

		/*
		 * e. Tell the next owner we're done
		 * Make sure we've updated the hardware first, so that we don't
		 * race to update prod and potentially move it backwards.
		 */
		atomic_set_release(&mcmdq->owner_prod, prod);
	}

	/* 5. If we are inserting a CMD_SYNC, we must wait for it to complete */
	if (sync) {
		llq.prod = ummu_queue_inc_prod_n(&llq, n);

		ret = ummu_mcmdq_poll_until_sync(ummu, mcmdq, &llq);
		if (ret)
			dev_err_ratelimited(
				ummu->dev,
				"CMD_SYNC timeout at 0x%08x [hwprod 0x%08x, hwcons 0x%08x]\n",
				llq.prod, readl_relaxed(mcmdq->q.prod_reg),
				readl_relaxed(mcmdq->q.cons_reg));

		ret = check_pa_continuity_nop_exec(&mcmdq->q, sprod);
		/*
		 * Try to unlock the mcmdq lock. This will fail if we're the last
		 * reader, in which case we can safely update mcmdq->q.llq.cons
		 */
		if (!ummu_mcmdq_shared_tryunlock(mcmdq)) {
			WRITE_ONCE(mcmdq->q.llq.cons, llq.cons);
			ummu_mcmdq_shared_unlock(mcmdq);
		}
	}

	local_irq_restore(flags);
	return ret;
}

static bool non_va_range_tlbi(int opcode)
{
	switch (opcode) {
	case CMD_TLBI_OS_ALL:
	case CMD_TLBI_OS_TID:
	case CMD_TLBI_HYP_ALL:
	case CMD_TLBI_HYP_TID:
	case CMD_TLBI_S1S2_VMALL:
	case CMD_TLBI_NS_OS_ALL:
	case CMD_TLBI_OS_ALL_U:
	case CMD_TLBI_OS_ASID_U:
	case CMD_TLBI_HYP_ASID_U:
	case CMD_TLBI_S1S2_VMALL_U:
		return true;
	default:
		return false;
	}
}

static int __ummu_mcmdq_issue_cmd(struct ummu_device *ummu,
				  struct ummu_mcmdq_ent *ent, bool sync)
{
	u64 cmds[2 * MCMDQ_ENT_DWORDS];
	int num = 1;

	if (unlikely(ummu_mcmdq_build_cmd(ummu, cmds, ent))) {
		dev_warn(ummu->dev, "ignoring unknown MCMDQ opcode = 0x%x\n",
			 ent->opcode);
		return -EINVAL;
	}

	if ((ummu->cap.options & UMMU_OPT_DOUBLE_TLBI) && non_va_range_tlbi(ent->opcode)) {
		memcpy(cmds + MCMDQ_ENT_DWORDS, cmds, MCMDQ_ENT_DWORDS * sizeof(u64));
		num = 2;
	}
	return ummu_mcmdq_issue_cmdlist(ummu, cmds, num, sync);
}

int ummu_mcmdq_issue_cmd(struct ummu_device *ummu, struct ummu_mcmdq_ent *ent)
{
	return __ummu_mcmdq_issue_cmd(ummu, ent, false);
}

int ummu_mcmdq_issue_cmd_with_sync(struct ummu_device *ummu,
				   struct ummu_mcmdq_ent *ent)
{
	return __ummu_mcmdq_issue_cmd(ummu, ent, true);
}

void ummu_mcmdq_batch_add(struct ummu_device *ummu,
			  struct ummu_mcmdq_batch *cmds,
			  struct ummu_mcmdq_ent *cmd)
{
	int index;

	if (cmds->num == MCMDQ_BATCH_ENTRIES) {
		(void)ummu_mcmdq_issue_cmdlist(ummu, cmds->cmds, cmds->num, false);
		cmds->num = 0;
	}

	index = cmds->num * MCMDQ_ENT_DWORDS;
	if (unlikely(ummu_mcmdq_build_cmd(ummu, &cmds->cmds[index], cmd))) {
		dev_warn(ummu->dev, "ignoring unknown MCMDQ opcode = 0x%x\n",
			 cmd->opcode);
		return;
	}

	cmds->num++;
}

int ummu_mcmdq_batch_submit(struct ummu_device *ummu,
			    struct ummu_mcmdq_batch *cmds)
{
	return ummu_mcmdq_issue_cmdlist(ummu, cmds->cmds, cmds->num, true);
}
