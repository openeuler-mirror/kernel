// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
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

BPF_CALL_1(bpf_sched_entity_to_tgidpid, struct sched_entity *, se)
{
	if (entity_is_task(se)) {
		struct task_struct *task = task_of(se);

		return (u64) task->tgid << 32 | task->pid;
	} else {
		return (u64) -1;
	}
}

BPF_CALL_1(bpf_sched_entity_to_cgrpid, struct sched_entity *, se)
{
#ifdef CONFIG_FAIR_GROUP_SCHED
	if (!entity_is_task(se))
		return cgroup_id(se->my_q->tg->css.cgroup);
#endif
	return (u64) -1;
}

BPF_CALL_2(bpf_sched_entity_belongs_to_cgrp, struct sched_entity *, se,
	   u64, cgrpid)
{
#ifdef CONFIG_CGROUPS
	struct cgroup *cgrp;
	int level;

	if (entity_is_task(se))
		cgrp = task_dfl_cgroup(task_of(se));
#ifdef CONFIG_FAIR_GROUP_SCHED
	else
		cgrp = se->my_q->tg->css.cgroup;
#endif

	for (level = cgrp->level; level; level--)
		if (cgrp->ancestor_ids[level] == cgrpid)
			return 1;
#endif
	return 0;
}

BTF_ID_LIST_SINGLE(btf_sched_entity_ids, struct, sched_entity)

static const struct bpf_func_proto bpf_sched_entity_to_tgidpid_proto = {
	.func		= bpf_sched_entity_to_tgidpid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_sched_entity_ids[0],
};

static const struct bpf_func_proto bpf_sched_entity_to_cgrpid_proto = {
	.func		= bpf_sched_entity_to_cgrpid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_sched_entity_ids[0],
};

static const struct bpf_func_proto bpf_sched_entity_belongs_to_cgrp_proto = {
	.func		= bpf_sched_entity_belongs_to_cgrp,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_sched_entity_ids[0],
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_1(bpf_sched_tg_tag_of, struct task_group *, tg)
{
	int ret = 0;

#ifdef CONFIG_CGROUP_SCHED
	if (tg == NULL)
		return -EINVAL;
	ret = tg->tag;
#endif

	return ret;
}

BTF_ID_LIST_SINGLE(btf_sched_tg_ids, struct, task_group)

const struct bpf_func_proto bpf_sched_tg_tag_of_proto = {
	.func		= bpf_sched_tg_tag_of,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= PTR_MAYBE_NULL | ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_sched_tg_ids[0],
};

BPF_CALL_1(bpf_sched_task_tag_of, struct task_struct *, tsk)
{
	if (tsk == NULL)
		return -EINVAL;
	return tsk->tag;
}

BTF_ID_LIST_SINGLE(btf_sched_task_ids, struct, task_struct)

const struct bpf_func_proto bpf_sched_task_tag_of_proto = {
	.func		= bpf_sched_task_tag_of,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= PTR_MAYBE_NULL | ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_sched_task_ids[0],
};

BPF_CALL_1(bpf_sched_entity_is_task, struct sched_entity *, se)
{
	return entity_is_task(se) ? 1 : 0;
}

static const struct bpf_func_proto bpf_sched_entity_is_task_proto = {
	.func		= bpf_sched_entity_is_task,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_sched_entity_ids[0],
};

BPF_CALL_1(bpf_sched_entity_to_task, struct sched_entity *, se)
{
	if (entity_is_task(se)) {
		struct task_struct *tsk = task_of(se);

		return (unsigned long)tsk;
	}

	return (unsigned long)NULL;
}

static const struct bpf_func_proto bpf_sched_entity_to_task_proto = {
	.func		= bpf_sched_entity_to_task,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_BTF_ID_OR_NULL,
	.ret_btf_id	= &btf_sched_task_ids[0],
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_sched_entity_ids[0],
};

BPF_CALL_1(bpf_sched_entity_to_tg, struct sched_entity *, se)
{
#if CONFIG_FAIR_GROUP_SCHED
	if (!entity_is_task(se)) {
		struct task_group *tg = group_cfs_rq(se)->tg;

		return (unsigned long)tg;
	}
#endif

	return (unsigned long)NULL;
}

static const struct bpf_func_proto bpf_sched_entity_to_tg_proto = {
	.func		= bpf_sched_entity_to_tg,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_BTF_ID_OR_NULL,
	.ret_btf_id	= &btf_sched_tg_ids[0],
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_sched_entity_ids[0],
};

BPF_CALL_2(bpf_sched_set_tg_tag, struct task_group *, tg, s64, tag)
{
#if CONFIG_CGROUP_SCHED
	if (tg == NULL || tg == &root_task_group)
		return -EINVAL;

	if (tg->tag == tag)
		return 0;

	rcu_read_lock();
	walk_tg_tree_from(tg, tg_change_tag, tg_nop, (void *)(&tag));
	rcu_read_unlock();

	return 0;
#endif
	return -EPERM;
}

const struct bpf_func_proto bpf_sched_set_tg_tag_proto = {
	.func		= bpf_sched_set_tg_tag,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= PTR_MAYBE_NULL | ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_sched_tg_ids[0],
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_sched_set_task_tag, struct task_struct *, tsk, s64, tag)
{
	if (tsk == NULL)
		return -EINVAL;

	sched_settag(tsk, tag);
	return 0;
}

const struct bpf_func_proto bpf_sched_set_task_tag_proto = {
	.func		= bpf_sched_set_task_tag,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= PTR_MAYBE_NULL | ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_sched_task_ids[0],
	.arg2_type	= ARG_ANYTHING,
};
static const struct bpf_func_proto *
bpf_sched_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	case BPF_FUNC_sched_entity_to_tgidpid:
		return &bpf_sched_entity_to_tgidpid_proto;
	case BPF_FUNC_sched_entity_to_cgrpid:
		return &bpf_sched_entity_to_cgrpid_proto;
	case BPF_FUNC_sched_entity_belongs_to_cgrp:
		return &bpf_sched_entity_belongs_to_cgrp_proto;
	case BPF_FUNC_sched_entity_is_task:
		return &bpf_sched_entity_is_task_proto;
	case BPF_FUNC_sched_entity_to_task:
		return &bpf_sched_entity_to_task_proto;
	case BPF_FUNC_sched_entity_to_tg:
		return &bpf_sched_entity_to_tg_proto;
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
