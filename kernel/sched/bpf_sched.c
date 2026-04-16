// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/cgroup.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf_sched.h>
#include <linux/btf_ids.h>
#include "sched.h"

DEFINE_STATIC_KEY_FALSE(bpf_sched_enabled_key);

/*
 * For every hook declare a nop function where a BPF program can be attached.
 */
#define BPF_SCHED_HOOK(RET, DEFAULT, NAME, ...)	\
noinline RET bpf_sched_##NAME(__VA_ARGS__)	\
{						\
	return DEFAULT;				\
}

#include <linux/sched_hook_defs.h>
#undef BPF_SCHED_HOOK

#define BPF_SCHED_HOOK(RET, DEFAULT, NAME, ...) BTF_ID(func, bpf_sched_##NAME)
BTF_SET_START(bpf_sched_hooks)
#include <linux/sched_hook_defs.h>
#undef BPF_SCHED_HOOK
BTF_SET_END(bpf_sched_hooks)

int bpf_sched_verify_prog(struct bpf_verifier_log *vlog,
			  const struct bpf_prog *prog)
{
	if (!prog->gpl_compatible) {
		bpf_log(vlog,
			"sched programs must have a GPL compatible license\n");
		return -EINVAL;
	}

	if (!btf_id_set_contains(&bpf_sched_hooks, prog->aux->attach_btf_id)) {
		bpf_log(vlog, "attach_btf_id %u points to wrong type name %s\n",
			prog->aux->attach_btf_id, prog->aux->attach_func_name);
		return -EINVAL;
	}

	return 0;
}

static const struct bpf_func_proto *
bpf_sched_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	default:
		return bpf_base_func_proto(func_id);
	}
}

const struct bpf_prog_ops bpf_sched_prog_ops = {
};

const struct bpf_verifier_ops bpf_sched_verifier_ops = {
	.get_func_proto = bpf_sched_func_proto,
	.is_valid_access = btf_ctx_access,
};

static struct bpf_mem_alloc bpf_cpustats_ma;

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in BTF");

/**
 * bpf_sched_cpu_stats_create() - Create a mutable BPF cpustats context.
 *
 * Allocates a cpustats context that can be queried, mutated, acquired, and
 * released by a BPF program. The cpustats context returned by this function
 * must either be embedded in a map as a kptr, or freed with
 * bpf_sched_cpu_stats_release().
 *
 * bpf_sched_cpu_stats_create() allocates memory using the BPF memory allocator,
 * and will not block. It may return NULL if no memory is available.
 */
__bpf_kfunc struct bpf_sched_cpu_stats *bpf_sched_cpustats_create(void)
{
	struct bpf_sched_cpu_stats *cpustats;

	cpustats = bpf_mem_cache_alloc(&bpf_cpustats_ma);
	if (!cpustats)
		return NULL;

	memset(cpustats, 0, sizeof(*cpustats));
	refcount_set(&cpustats->usage, 1);

	return cpustats;
}

/**
 * bpf_sched_cpu_stats_acquire() - Acquire a reference to a BPF cpustats.
 * @cpustats: The BPF cpustats being acquired. The cpustats must be a trusted
 *	      pointer.
 *
 * Acquires a reference to a BPF cpustats. The cpustats returned by this
 * function must either be embedded in a map as a kptr, or freed with
 * bpf_sched_cpu_stats_release().
 */
__bpf_kfunc struct bpf_sched_cpu_stats *bpf_sched_cpustats_acquire(
					struct bpf_sched_cpu_stats *cpustats)
{
	refcount_inc(&cpustats->usage);
	return cpustats;
}

/**
 * bpf_sched_cpustats_release() - Release a previously acquired BPF cpustats.
 * @cpustats: The cpustats being released.
 *
 * Releases a previously acquired reference to a BPF cpustats. When the final
 * reference of the BPF cpustats has been released, it is subsequently freed in
 * an RCU callback in the BPF memory allocator.
 */
__bpf_kfunc void
bpf_sched_cpustats_release(struct bpf_sched_cpu_stats *cpustats)
{
	if (!refcount_dec_and_test(&cpustats->usage))
		return;

	migrate_disable();
	bpf_mem_cache_free_rcu(&bpf_cpustats_ma, cpustats);
	migrate_enable();
}

/**
 * bpf_sched_cpu_stats_of() - Acquire cpu sched statistics.
 * @cpuid: CPU ID, input.
 * @ctx: The cpu statistics is being stored.
 *
 * Return:
 *    0   - Success.
 *   <0   - Fail.
 */
__bpf_kfunc s32 bpf_sched_cpu_stats_of(int cpuid,
				       struct bpf_sched_cpu_stats *ctx)
{
	struct rq *rq;
	int cpu = cpuid;

	if (!ctx)
		return -EINVAL;

	if ((unsigned int)cpu >= nr_cpu_ids)
		return -EINVAL;

	rq = cpu_rq(cpu);

	SCHED_WARN_ON(!rcu_read_lock_held());
	/* nr_running */
	ctx->nr_running = rq->nr_running;
	ctx->cfs_nr_running = rq->cfs.nr_running;
	ctx->cfs_h_nr_running = rq->cfs.h_nr_running;
	ctx->cfs_idle_h_nr_running = rq->cfs.idle_h_nr_running;
	ctx->rt_nr_running = rq->rt.rt_nr_running;
	ctx->rr_nr_running = rq->rt.rr_nr_running;

	return 0;
}

__diag_pop();

BTF_KFUNCS_START(sched_cpustats_kfunc_btf_ids)
BTF_ID_FLAGS(func, bpf_sched_cpustats_create, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_sched_cpustats_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_sched_cpustats_acquire, KF_ACQUIRE | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_sched_cpu_stats_of, KF_RCU)
BTF_KFUNCS_END(sched_cpustats_kfunc_btf_ids)

static const struct btf_kfunc_id_set cpustats_kfunc_set = {
	.owner		= THIS_MODULE,
	.set		= &sched_cpustats_kfunc_btf_ids,
};

BTF_ID_LIST(cpustats_dtor_ids)
BTF_ID(struct, bpf_sched_cpu_stats)
BTF_ID(func, bpf_sched_cpustats_release)

__bpf_kfunc int bpf_sched_entity_is_task(struct sched_entity *se)
{
	if (!se)
		return -EINVAL;

	return entity_is_task(se);
}

__bpf_kfunc struct task_struct *bpf_sched_entity_to_task(struct sched_entity *se)
{
	if (se && entity_is_task(se))
		return task_of(se);

	return NULL;
}

__bpf_kfunc long bpf_sched_tag_of_entity(struct sched_entity *se)
{
	if (!se)
		return -EINVAL;

	if (entity_is_task(se))
		return task_of(se)->tag;

	return group_cfs_rq(se)->tg->tag;
}

__bpf_kfunc int bpf_sched_set_task_prefer_nid(struct task_struct *task, int nid)
{
	cpumask_t mask;

	if (!task)
		return -EINVAL;

	if ((unsigned int)nid >= nr_node_ids)
		return -EINVAL;

	cpumask_and(&mask, task->cpus_ptr, cpumask_of_node(nid));
	return set_prefer_cpus_ptr(task, &mask);
}

BTF_KFUNCS_START(sched_task_kfunc_btf_ids)
BTF_ID_FLAGS(func, bpf_sched_entity_is_task)
BTF_ID_FLAGS(func, bpf_sched_entity_to_task)
BTF_ID_FLAGS(func, bpf_sched_tag_of_entity)
BTF_ID_FLAGS(func, bpf_sched_set_task_prefer_nid)
BTF_KFUNCS_END(sched_task_kfunc_btf_ids)

static const struct btf_kfunc_id_set sched_task_kfunc_set = {
	.owner		= THIS_MODULE,
	.set		= &sched_task_kfunc_btf_ids,
};

BTF_ID_LIST(sched_task_dtor_ids)

static int __init bpf_kfunc_init(void)
{
	int ret;
	const struct btf_id_dtor_kfunc cpustats_dtors[] = {
		{
			.btf_id	      = cpustats_dtor_ids[0],
			.kfunc_btf_id = cpustats_dtor_ids[1]
		},
	};
	const struct btf_id_dtor_kfunc sched_task_dtors[] = {
		{
			.btf_id	      = sched_task_dtor_ids[0],
			.kfunc_btf_id = sched_task_dtor_ids[1]
		},
	};

	ret = bpf_mem_alloc_init(&bpf_cpustats_ma, sizeof(struct bpf_sched_cpu_stats), false);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &cpustats_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED, &cpustats_kfunc_set);
	ret = ret ?: register_btf_id_dtor_kfuncs(cpustats_dtors,
						ARRAY_SIZE(cpustats_dtors),
						THIS_MODULE);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED, &sched_task_kfunc_set);
	return ret ?: register_btf_id_dtor_kfuncs(sched_task_dtors,
						ARRAY_SIZE(sched_task_dtors),
						THIS_MODULE);
}
late_initcall(bpf_kfunc_init);
