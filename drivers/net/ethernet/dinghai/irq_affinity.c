// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/dinghai_irq.h>
#include <linux/dinghai/pci_irq.h>
#include <linux/dinghai/helper.h>

static void cpu_put(struct dh_irq_pool *pool, s32 cpu)
{
	pool->irqs_per_cpu[cpu]--;
}

static void cpu_get(struct dh_irq_pool *pool, s32 cpu)
{
	pool->irqs_per_cpu[cpu]++;
}

/* Gets the least loaded CPU. e.g.: the CPU with least IRQs bound to it */
static s32 cpu_get_least_loaded(struct dh_irq_pool *pool, const struct cpumask *req_mask)
{
	s32 best_cpu = -1;
	s32 cpu;

	if (!pool || !pool->irqs_per_cpu) {
		LOG_ERR("pool or irqs_per_cpu is NULL\n");
		return -EINVAL;
	}

	for_each_cpu_and(cpu, req_mask, cpu_online_mask) {
		/* CPU has zero IRQs on it. No need to search any more CPUs. */
		if (!pool->irqs_per_cpu[cpu]) {
			best_cpu = cpu;
			break;
		}
		if (best_cpu < 0)
			best_cpu = cpu;
		if (pool->irqs_per_cpu[cpu] < pool->irqs_per_cpu[best_cpu])
			best_cpu = cpu;
	}

	if (best_cpu == -1) {
		/* There isn't online CPUs in req_mask */
		LOG_ERR("NO online CPUs in req_mask (%*pbl)\n", cpumask_pr_args(req_mask));
		best_cpu = cpumask_first(cpu_online_mask);
	}
	pool->irqs_per_cpu[best_cpu]++;

	return best_cpu;
}

/* Creating an IRQ from irq_pool */
struct dh_irq *irq_pool_request_irq(struct dh_irq_pool *pool, const struct cpumask *req_mask)
{
	cpumask_var_t auto_mask;
	struct dh_irq *irq = NULL;
	u32 irq_index = 0;
	s32 err = 0;

	if (!zalloc_cpumask_var(&auto_mask, GFP_KERNEL)) {
		LOG_ERR("zalloc_cpumask_var failed, ERR_PTR(-ENOMEM)=0x%llx",
			(unsigned long long)ERR_PTR(-ENOMEM));
		return ERR_PTR(-ENOMEM);
	}

	err = xa_alloc(&pool->irqs, &irq_index, NULL, pool->xa_num_irqs, GFP_KERNEL);
	if (err) {
		if (err == -EBUSY)
			err = -EUSERS;
		LOG_ERR("xa_alloc failed, ERR_PTR(err)=0x%llx", (unsigned long long)ERR_PTR(err));
		return ERR_PTR(err);
	}

	if (pool->irqs_per_cpu) {
		if (cpumask_weight(req_mask) > 1) {
			/* if req_mask contain more then one CPU, set the least loadad CPU
			 * of req_mask
			 */
			cpumask_set_cpu(cpu_get_least_loaded(pool, req_mask), auto_mask);
		} else {
			cpu_get(pool, cpumask_first(req_mask));
		}
	}

	irq = dh_irq_alloc(pool, irq_index, cpumask_empty(auto_mask) ? req_mask : auto_mask);
	if (IS_ERR_OR_NULL(irq)) {
		LOG_ERR("dh_irq_alloc failed, irq=%p\n", irq);
		return irq;
	}
	free_cpumask_var(auto_mask);

	return irq;
}

/* Looking for the IRQ with the smallest refcount that fits req_mask.
 * If pool is sf_comp_pool, then we are looking for an IRQ with any of the
 * requested CPUs in req_mask.
 * for example: req_mask = 0xf, irq0_mask = 0x10, irq1_mask = 0x1. irq0_mask
 * isn't subset of req_mask, so we will skip it. irq1_mask is subset of req_mask,
 * we don't skip it.
 * If pool is sf_ctrl_pool, then all IRQs have the same mask, so any IRQ will
 * fit. And since mask is subset of itself, we will pass the first if bellow.
 */
static struct dh_irq *irq_pool_find_least_loaded(struct dh_irq_pool *pool,
						 const struct cpumask *req_mask)
{
	s32 start = pool->xa_num_irqs.min;
	s32 end = pool->xa_num_irqs.max;
	struct dh_irq *irq = NULL;
	struct dh_irq *iter;
	s32 irq_refcount = 0;
	unsigned long index;

	lockdep_assert_held(&pool->lock);
	xa_for_each_range(&pool->irqs, index, iter, start, end) {
		struct cpumask *iter_mask = dh_irq_get_affinity_mask(iter);
		s32 iter_refcount = dh_irq_read_locked(iter);

		if (!cpumask_subset(iter_mask, req_mask)) {
			/* skip IRQs with a mask which is not subset of req_mask */
			continue;
		}
		if (iter_refcount < pool->min_threshold) {
			/* If we found an IRQ with less than min_thres, return it */
			return iter;
		}
		if (!irq || iter_refcount < irq_refcount) {
			/* In case we won't find an IRQ with less than min_thres,
			 * keep a pointer to the least used IRQ
			 */
			irq_refcount = iter_refcount;
			irq = iter;
		}
	}

	return irq;
}

/**
 * dh_irq_affinity_request - request an IRQ according to the given mask.
 * @pool: IRQ pool to request from.
 * @req_mask: cpumask requested for this IRQ.
 *
 * This function returns a pointer to IRQ, or ERR_PTR in case of error.
 */
struct dh_irq *dh_irq_affinity_request(struct dh_irq_pool *pool, const struct cpumask *req_mask)
{
	struct dh_irq *least_loaded_irq = NULL;
	struct dh_irq *new_irq = NULL;

	mutex_lock(&pool->lock);

	least_loaded_irq = irq_pool_find_least_loaded(pool, req_mask);
	if (least_loaded_irq && dh_irq_read_locked(least_loaded_irq) < pool->min_threshold) {
		LOG_ERR("least_loaded_irq error: pool->min_threshold=%d\r\n", pool->min_threshold);
		goto out;
	}

	/* We didn't find an IRQ with less than min_thres, try to allocate a new IRQ */
	new_irq = irq_pool_request_irq(pool, req_mask);
	if (IS_ERR_OR_NULL(new_irq)) {
		if (!least_loaded_irq) {
			/* We failed to create an IRQ and we didn't find an IRQ */
			LOG_ERR("Didn't find a matching IRQ. err = %ld\n", PTR_ERR(new_irq));
			mutex_unlock(&pool->lock);
			return new_irq;
		}
		/* We failed to create a new IRQ for the requested affinity,
		 * sharing existing IRQ.
		 */
		LOG_ERR("new_irq error\r\n");
		goto out;
	}

	least_loaded_irq = new_irq;
	goto unlock;

out:
	dh_irq_get_locked(least_loaded_irq);
	if (dh_irq_read_locked(least_loaded_irq) > pool->max_threshold)
		LOG_DEBUG("IRQ %u overloaded, pool_name: %s, %u EQs on this irq\n",
			  pci_irq_vector(pool->dev->pdev, dh_irq_get_index(least_loaded_irq)),
			  pool->name, dh_irq_read_locked(least_loaded_irq) / DH_EQ_REFS_PER_IRQ);
unlock:
	mutex_unlock(&pool->lock);
	return least_loaded_irq;
}

void dh_irq_affinity_irqs_release(struct dh_irq_pool *pool, struct dh_irq **irqs, s32 num_irqs)
{
	s32 i;

	for (i = 0; i < num_irqs; i++) {
		s32 cpu = cpumask_first(dh_irq_get_affinity_mask(irqs[i]));

		synchronize_irq(pci_irq_vector(pool->dev->pdev, dh_irq_get_index(irqs[i])));

		if (pool->irqs_per_cpu)
			cpu_put(pool, cpu);
	}
}

/**
 * dh_irq_affinity_irqs_request_auto - request one or more IRQs for zxdh device.
 * @pool: requesting the IRQs from the irqs pool.
 * @num_irqs: number of IRQs to request.
 * @irqs: an output array of IRQs pointers.
 * @numa: NUMA node of the CPU that handles the IRQS.
 *
 * Each IRQ is bounded to at most 1 CPU.
 * This function is requesting IRQs according to the default assignment.
 * The default assignment policy is:
 * - in each iteration, request the least loaded IRQ which is not bound to any
 *   CPU of the previous IRQs requested.
 *
 * This function returns the number of IRQs requested, (which might be smaller than
 * @nirqs), if successful, or a negative error code in case of an error.
 */
s32 dh_irq_affinity_irqs_request_auto(struct dh_irq_pool *pool, struct dh_irq **irqs, s32 num_irqs,
				      int numa)
{
	cpumask_var_t req_mask;
	struct dh_irq *irq = NULL;
	s32 i, j;
	int num_cpus;
	int *cpus = NULL;
	int cpu_index;
	int pair_offset;
	int irq_idx = 0;

	if (!zalloc_cpumask_var(&req_mask, GFP_KERNEL)) {
		LOG_ERR("zalloc_cpumask_var failed for req_mask\n");
		return -ENOMEM;
	}

	if (numa == NUMA_NO_NODE) {
		LOG_INFO("NUMA_NO_NODE\n");
		cpumask_copy(req_mask, cpu_online_mask);
	} else {
		cpumask_copy(req_mask, cpumask_of_node(numa));
		cpumask_and(req_mask, req_mask, cpu_online_mask);
	}
	num_cpus = cpumask_weight(req_mask);
	if (num_cpus == 0) {
		LOG_ERR("NUMA node %d has no online CPUs!\n", numa);
		goto clean_req_mask;
	}

	cpus = kcalloc(num_cpus, sizeof(*cpus), GFP_KERNEL);
	if (!cpus) {
		LOG_ERR("cpus kcalloc failed!\n");
		goto clean_req_mask;
	}

	j = 0;
	for_each_cpu(i, req_mask)
		cpus[j++] = i;

	for (i = 0; i < num_irqs; i += 2) {
		cpu_index = (i / 2) % num_cpus;

		cpumask_clear(req_mask);
		cpumask_set_cpu(cpus[cpu_index], req_mask);

		for (pair_offset = 0; pair_offset < 2; pair_offset++) {
			irq_idx = i + pair_offset;
			if (irq_idx >= num_irqs)
				goto out;
			irq = irq_pool_request_irq(pool, req_mask);
			if (IS_ERR_OR_NULL(irq)) {
				LOG_ERR("irq_pool_request_irq %d failed, req_mask=%p, irq=%p",
					irq_idx, req_mask, irq);
				goto cleanup;
			}
			irqs[irq_idx] = irq;
			LOG_DEBUG("IRQ %u mapped to cpu %*pbl, %u EQs on this irq\n",
				  pci_irq_vector(pool->dev->pdev, dh_irq_get_index(irq)),
				  cpumask_pr_args(dh_irq_get_affinity_mask(irq)),
				  dh_irq_read_locked(irq) / DH_EQ_REFS_PER_IRQ);
		}
	}

out:
	free_cpumask_var(req_mask);
	kfree(cpus);
	return num_irqs;

cleanup:
	kfree(cpus);
	dh_irq_affinity_irqs_release(pool, irqs, irq_idx);
	dh_irqs_release_vectors(irqs, irq_idx);
clean_req_mask:
	free_cpumask_var(req_mask);
	return PTR_ERR(irq);
}
