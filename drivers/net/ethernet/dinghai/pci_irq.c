// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/interrupt.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include <linux/dinghai/pci_irq.h>
#include <linux/dinghai/helper.h>
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/lockdep.h>
#include <linux/device.h>
#include <linux/dinghai/dinghai_irq.h>

#define DH_PF_IRQ_CTRL_NUM (1)

#define DH_SFS_PER_CTRL_IRQ 64
#define DH_IRQ_CTRL_SF_MAX 8
/* min num of vectors for SFs to be enabled */
#define DH_IRQ_VEC_COMP_BASE_SF 2

#define DH_EQ_SHARE_IRQ_MAX_COMP (8)
#define DH_EQ_SHARE_IRQ_MAX_CTRL (UINT_MAX)
#define DH_EQ_SHARE_IRQ_MIN_COMP (1)
#define DH_EQ_SHARE_IRQ_MIN_CTRL (4)

static void irq_release(struct dh_irq *irq)
{
	struct dh_irq_pool *pool = irq->pool;

	xa_erase(&pool->irqs, irq->index);
	/* free_irq requires that affinity_hint and rmap will be cleared
	 * before calling it. This is why there is asymmetry with set_rmap
	 * which should be called after alloc_irq but before request_irq.
	 */
	// irq_update_affinity_hint(irq->irqn, NULL);
	irq_set_affinity_hint(irq->irqn, NULL);
	free_cpumask_var(irq->mask);
	free_irq(irq->irqn, &irq->nh);
	kfree(irq);
}

s32 dh_irq_put(struct dh_irq *irq)
{
	struct dh_irq_pool *pool = irq->pool;
	s32 ret = 0;

	mutex_lock(&pool->lock);
	irq->refcount--;
	if (!irq->refcount) {
		/* Hide from new lookups under lock; free_irq must run
		 * outside the lock because it calls synchronize_irq()
		 * which may block waiting for in-flight handlers.
		 */
		xa_erase(&pool->irqs, irq->index);
		ret = 1;
	}
	mutex_unlock(&pool->lock);

	if (ret)
		irq_release(irq);

	return ret;
}

s32 dh_irq_read_locked(struct dh_irq *irq)
{
	lockdep_assert_held(&irq->pool->lock);

	return irq->refcount;
}

s32 dh_irq_get_locked(struct dh_irq *irq)
{
	lockdep_assert_held(&irq->pool->lock);
	if (WARN_ON_ONCE(!irq->refcount))
		return 0;

	irq->refcount++;

	return 1;
}

static s32 irq_get(struct dh_irq *irq)
{
	s32 err = 0;

	mutex_lock(&irq->pool->lock);
	err = dh_irq_get_locked(irq);
	mutex_unlock(&irq->pool->lock);

	return err;
}

static irqreturn_t irq_int_handler(s32 irq, void *data)
{
	struct dh_irq *dh_irq = NULL;

	dh_irq = (struct dh_irq *)data;
	atomic_notifier_call_chain(&dh_irq->nh, 0, dh_irq->pool->data);

	return IRQ_HANDLED;
}

static void irq_set_name(struct dh_irq_pool *pool, char *name, s32 vecidx)
{
	if (!strcmp(pool->name, "zxdh_pf_vq")) {
		int type = (vecidx - pool->xa_num_irqs.min) % 2;

		snprintf(name, DH_MAX_IRQ_NAME, "vq_%s_%d", type ? "output" : "input", vecidx);
		return;
	} else if (!strcmp(pool->name, "zxdh_pf_async")) {
		snprintf(name, DH_MAX_IRQ_NAME, "async_%d", vecidx);
		return;
	} else if (!strcmp(pool->name, "zxdh_mpf_gdma")) {
		snprintf(name, DH_MAX_IRQ_NAME, "gdma_%d", vecidx);
		return;
	}
}

struct dh_irq *dh_irq_alloc(struct dh_irq_pool *pool, s32 i, const struct cpumask *affinity)
{
	struct dh_core_dev *dev = pool->dev;
	char name[DH_MAX_IRQ_NAME] = {};
	struct dh_irq *irq = NULL;
	s32 err = 0;
	s32 num_cpu = 0;
	s32 cpu_loop = 0;

	irq = kzalloc(sizeof(*irq), GFP_KERNEL);
	if (unlikely(!irq))
		return ERR_PTR(-ENOMEM);

	irq->pool = pool;
	irq->irqn = pci_irq_vector(dev->pdev, i);
	irq_set_name(pool, name, i);
	ATOMIC_INIT_NOTIFIER_HEAD(&irq->nh);
	snprintf(irq->name, DH_MAX_IRQ_NAME, "%s@pci:%s", name, pci_name(dev->pdev));
	LOG_DEBUG("i=%d, irqn=%d, name=%s\r\n", i, irq->irqn, irq->name);

	err = request_irq(irq->irqn, irq_int_handler, 0, irq->name, irq);
	if (err != 0) {
		LOG_ERR("Failed to request irq. err = %d\n", err);
		goto err_req_irq;
	}

	if (!zalloc_cpumask_var(&irq->mask, GFP_KERNEL)) {
		LOG_WARN("zalloc_cpumask_var failed\n");
		err = -ENOMEM;
		goto err_cpumask;
	}

	if (affinity) {
		cpumask_copy(irq->mask, affinity);
		irq_set_affinity_hint(irq->irqn, irq->mask);
	} else {
		num_cpu = num_online_cpus();
		for (cpu_loop = 0; cpu_loop < num_cpu; cpu_loop++)
			cpumask_set_cpu(cpu_loop, irq->mask);
		irq_set_affinity_hint(irq->irqn, irq->mask);
	}

	irq->refcount = 1;
	irq->index = i;
	err = xa_err(xa_store(&pool->irqs, irq->index, irq, GFP_KERNEL));
	if (err != 0) {
		LOG_ERR("Failed to alloc xa entry for irq(%u). err = %d\n", irq->index, err);
		goto err_xa;
	}

	return irq;

err_xa:
	irq_set_affinity_hint(irq->irqn, NULL);
	free_cpumask_var(irq->mask);
err_cpumask:
	free_irq(irq->irqn, &irq->nh);
err_req_irq:
	kfree(irq);
	return ERR_PTR(err);
}

s32 dh_irq_attach_nb(struct dh_irq *irq, struct notifier_block *nb)
{
	s32 ret = 0;

	ret = irq_get(irq);
	if (!ret)
		return -ENOENT;

	ret = atomic_notifier_chain_register(&irq->nh, nb);
	if (ret != 0)
		dh_irq_put(irq);

	return ret;
}

s32 dh_irq_detach_nb(struct dh_irq *irq, struct notifier_block *nb)
{
	s32 err = 0;

	err = atomic_notifier_chain_unregister(&irq->nh, nb);
	dh_irq_put(irq);

	return err;
}

struct cpumask *dh_irq_get_affinity_mask(struct dh_irq *irq)
{
	return irq->mask;
}

s32 dh_irq_get_index(struct dh_irq *irq)
{
	return irq->index;
}

/**
 * dh_irqs_release - release one or more IRQs back to the system.
 * @irqs: IRQs to be released.
 * @nirqs: number of IRQs to be released.
 */
static void dh_irqs_release(struct dh_irq **irqs, s32 nirqs)
{
	s32 i;

	for (i = 0; i < nirqs; i++) {
		synchronize_irq(irqs[i]->irqn);
		dh_irq_put(irqs[i]);
	}
}

/* get a irq from pool*/
struct dh_irq *zxdh_get_irq_of_pool(struct dh_core_dev *dev, struct dh_irq_pool *pool)
{
	cpumask_var_t req_mask;
	struct dh_irq *irq = NULL;

	if (!zalloc_cpumask_var(&req_mask, GFP_KERNEL)) {
		LOG_ERR("zalloc_cpumask_var failed\n");
		return ERR_PTR(-ENOMEM);
	}
	cpumask_copy(req_mask, cpu_online_mask);

	irq = dh_irq_affinity_request(pool, req_mask);

	free_cpumask_var(req_mask);
	if (IS_ERR_OR_NULL(irq)) {
		LOG_ERR("irq=0x%llx dh_irq_affinity_request failed\n",
			(unsigned long long)(uintptr_t)irq);
	}

	return irq;
}

/**
 * dh_irqs_release_vectors - release one or more IRQs back to the system.
 * @irqs: IRQs to be released.
 * @nirqs: number of IRQs to be released.
 */
void dh_irqs_release_vectors(struct dh_irq **irqs, s32 nirqs)
{
	dh_irqs_release(irqs, nirqs);
}

struct dh_irq_pool *irq_pool_alloc(struct dh_core_dev *dev, s32 start, s32 size, char *name,
				   u32 min_threshold, u32 max_threshold)
{
	struct dh_irq_pool *pool = kvzalloc(sizeof(*pool), GFP_KERNEL);

	if (unlikely(!pool)) {
		LOG_ERR("pool kvzalloc failed\n");
		return ERR_PTR(-ENOMEM);
	}

	pool->dev = dev;
	mutex_init(&pool->lock);
	xa_init_flags(&pool->irqs, XA_FLAGS_ALLOC);
	pool->xa_num_irqs.min = start;
	pool->xa_num_irqs.max = start + size - 1;

	if (name)
		snprintf(pool->name, DH_MAX_IRQ_NAME - DH_MAX_IRQ_IDX_CHARS, "%s", name);

	pool->min_threshold = min_threshold * DH_EQ_REFS_PER_IRQ;
	pool->max_threshold = max_threshold * DH_EQ_REFS_PER_IRQ;

	return pool;
}

void irq_pool_free(struct dh_irq_pool *pool)
{
	struct dh_irq *irq = NULL;
	unsigned long index;
	u32 cpu;

	/* There are cases in which we are destrying the irq_table before
	 * freeing all the IRQs, fast teardown for example. Hence, free the irqs
	 * which might not have been freed.
	 */
	xa_for_each(&pool->irqs, index, irq) {
		irq_release(irq);
	}
	xa_destroy(&pool->irqs);
	mutex_destroy(&pool->lock);

	if (pool->irqs_per_cpu) {
		for_each_online_cpu(cpu) {
			WARN_ON(pool->irqs_per_cpu[cpu]);
		}
		kfree(pool->irqs_per_cpu);
	}

	kvfree(pool);
}

void dh_irq_table_cleanup(struct dh_core_dev *dev)
{
	if (dh_core_is_sf(dev))
		return;

	kvfree(dev->irq_table.priv);
}
